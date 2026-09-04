// @vitest-environment jsdom
import { beforeEach, describe, expect, it } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { stubBridge } from './setup/renderer'
import { FrpManager } from '../src/renderer/src/components/vpn/FrpManager'
import { useApp } from '../src/renderer/src/store/app'
import type { FrpSpec, VpnProfile } from '../src/renderer/src/types'

// "Give me a public URL for localhost:3000", rendered.
//
// Three of the four things asserted here are refusals, which is the shape of
// this feature: the one-click flow is easy, and every way it could be
// dishonest is a defect that renders perfectly.
//
//   - It must not publish anything before it has said what it is publishing.
//     A number typed into a box is one keystroke away from being the wrong
//     number, and the wrong number here is a database on the internet.
//   - It must not produce a URL it has no reason to believe in. ShellPilot
//     does not own a domain; a plausible-looking address that resolves to
//     nothing is worse than the form this replaces.
//   - It must not keep asking. A setup that reappears is not a setup.

const started: string[] = []
const reloaded: string[] = []
const tokens: { token: string; profileName: string }[] = []

const HOST_PROFILE = (): VpnProfile => ({
  id: 'vpn-host',
  workspaceId: useApp.getState().activeId(),
  name: 'Tunnel host',
  autoStart: false,
  spec: {
    kind: 'frp',
    serverAddr: 'frp.example.com',
    serverPort: 7000,
    auth: { method: 'token', tokenRef: { vaultEntryId: 'v1', field: 'token' } },
    transport: { protocol: 'tcp', tlsEnable: true },
    proxies: [],
    visitors: [],
    publicHost: {
      baseDomain: 'tunnel.example.com',
      scheme: 'https',
      confirmedAt: 1_700_000_000_000
    }
  }
})

const frpSpec = (): FrpSpec => useApp.getState().vpns[0].spec as FrpSpec

beforeEach(() => {
  started.length = 0
  reloaded.length = 0
  tokens.length = 0
  stubBridge({
    platform: () => Promise.resolve('darwin'),
    clipboard: { write: () => undefined },
    vpn: {
      list: () => Promise.resolve([]),
      probe: () => Promise.resolve(null),
      onStatus: () => () => undefined,
      start: (id: string) => {
        started.push(id)
        return Promise.resolve({ ok: true })
      },
      reload: (id: string) => {
        reloaded.push(id)
        return Promise.resolve({ ok: true })
      },
      frpToken: (req: { profileName: string; token: string }) => {
        tokens.push(req)
        return Promise.resolve({
          ok: true,
          tokenRef: { vaultEntryId: 'v-new', field: 'token' },
          vaultEntryId: 'v-new'
        })
      }
    }
  })
})

async function askForAUrl(port: string): Promise<ReturnType<typeof userEvent.setup>> {
  const user = userEvent.setup()
  render(<FrpManager />)
  await user.type(screen.getByLabelText('Local port'), port)
  await user.click(screen.getByRole('button', { name: /Get a public URL/ }))
  return user
}

describe('the one click says what it is about to publish, before it publishes it', () => {
  beforeEach(() => {
    useApp.setState({ vpns: [HOST_PROFILE()] })
  })

  it('names the local address and the public one, and has published nothing yet', async () => {
    await askForAUrl('3000')

    expect(
      await screen.findByText(
        'Anything answering on 127.0.0.1:3000 on this machine becomes reachable at https://port-3000.tunnel.example.com.'
      )
    ).toBeTruthy()
    expect(document.body.textContent).toContain(
      'Anyone who has that address can reach it. Nothing asks them for a password first.'
    )
    expect(document.body.textContent).toContain(
      'Traffic arrives through frp.example.com:7000, the frp server you set up.'
    )

    // Nothing has happened to the profile, and the engine has not been asked
    // for anything. The sentence above is what the user reads BEFORE the port
    // is exposed, not a description of what already was.
    expect(frpSpec().proxies).toEqual([])
    expect(started).toEqual([])
    expect(reloaded).toEqual([])
  })

  it('will not publish until the exposure is acknowledged', async () => {
    const user = await askForAUrl('3000')
    const button = await screen.findByRole('button', { name: /Publish/ })
    expect((button as HTMLButtonElement).disabled).toBe(true)

    await user.click(button)
    expect(frpSpec().proxies).toEqual([])
    expect(started).toEqual([])

    await user.click(screen.getByRole('switch'))
    expect((button as HTMLButtonElement).disabled).toBe(false)
  })

  it('publishes the port that was typed, on loopback, with the box ticked', async () => {
    const user = await askForAUrl('3000')
    await user.click(await screen.findByRole('switch'))
    await user.click(screen.getByRole('button', { name: /Publish/ }))

    await waitFor(() => expect(started).toEqual(['vpn-host']))
    const proxies = frpSpec().proxies
    expect(proxies).toHaveLength(1)
    expect(proxies[0].name).toBe('port-3000')
    expect(proxies[0].type).toBe('http')
    expect(proxies[0].localIp).toBe('127.0.0.1')
    expect(proxies[0].localPort).toBe(3000)
    expect(proxies[0].subdomain).toBe('port-3000')
    expect(proxies[0].acknowledgedExposure).toBe(true)
  })
})

describe('a tunnel host that is not set up is explained, not papered over', () => {
  beforeEach(() => {
    useApp.setState({ vpns: [] })
  })

  it('produces a reason and no address at all', async () => {
    await askForAUrl('3000')

    expect(document.body.textContent).toContain(
      'A public URL needs an frp server you control, with a domain pointed at it. ' +
        'Set that up once and this stops being a question.'
    )
    // The whole point. A URL here would be one ShellPilot invented, and it
    // would resolve to nothing.
    expect(document.body.textContent).not.toContain('://')
    expect(screen.queryByRole('button', { name: /^Publish$/ })).toBe(null)
  })

  it('explains a tunnel host whose domain was never filled in', async () => {
    const half = HOST_PROFILE()
    ;(half.spec as FrpSpec).publicHost = {
      baseDomain: '',
      scheme: 'https',
      confirmedAt: 1_700_000_000_000
    }
    useApp.setState({ vpns: [half] })

    await askForAUrl('3000')
    expect(document.body.textContent).toContain(
      '"Tunnel host" has no domain. frp routes a public name to this machine, but the name has to be one you own and have pointed at the server.'
    )
    expect(document.body.textContent).not.toContain('://')
  })
})

describe('the guided setup happens once', () => {
  beforeEach(() => {
    useApp.setState({ vpns: [] })
  })

  it('says what the operator has to own, and then stops saying it', async () => {
    const user = await askForAUrl('3000')
    await user.click(screen.getByRole('button', { name: /Set up a tunnel host/ }))

    // Said here, in full, once.
    expect(
      await screen.findByText(/ShellPilot does not host public addresses/)
    ).toBeTruthy()

    await user.type(screen.getByPlaceholderText('frp.example.com'), 'frp.example.com')
    await user.type(screen.getByPlaceholderText('tunnel.example.com'), 'tunnel.example.com')
    await user.type(screen.getByPlaceholderText('auth.token from frps.toml'), 'sekrit-token')

    // The single DNS record, written out to be copied rather than described.
    expect(document.body.textContent).toContain('*.tunnel.example.com  →  frp.example.com')
    await user.click(
      screen.getByRole('switch', {
        name: /I have created this record/
      })
    )
    await user.click(screen.getByRole('button', { name: /Finish setup/ }))

    // The setup is over, and the publish the user originally asked for
    // carries on by itself.
    await waitFor(() =>
      expect(
        screen.queryByText(/ShellPilot does not host public addresses/)
      ).toBe(null)
    )
    expect(
      await screen.findByText(
        'Anything answering on 127.0.0.1:3000 on this machine becomes reachable at https://port-3000.tunnel.example.com.'
      )
    ).toBeTruthy()
    expect(tokens.map((t) => t.token)).toEqual(['sekrit-token'])

    // And it does not come back. Asking for a second URL goes straight to the
    // publish dialog, with no offer to set anything up.
    await user.click(screen.getByRole('button', { name: /^Cancel$/ }))
    await user.click(screen.getByRole('button', { name: /Get a public URL/ }))
    expect(await screen.findByRole('button', { name: /Publish/ })).toBeTruthy()
    expect(screen.queryByRole('button', { name: /Set up a tunnel host/ })).toBe(null)
    expect(document.body.textContent).not.toContain('ShellPilot does not host public addresses')
  })

  it('stores the domain on the profile, so it survives the dialog closing', async () => {
    const user = await askForAUrl('3000')
    await user.click(screen.getByRole('button', { name: /Set up a tunnel host/ }))
    await user.type(screen.getByPlaceholderText('frp.example.com'), 'frp.example.com')
    await user.type(screen.getByPlaceholderText('tunnel.example.com'), '*.tunnel.example.com')
    await user.click(screen.getByRole('switch', { name: /I have created this record/ }))
    await user.click(screen.getByRole('button', { name: /Finish setup/ }))

    await waitFor(() => expect(useApp.getState().vpns).toHaveLength(1))
    const host = frpSpec().publicHost
    // The wildcard is not part of the zone name — `*.tunnel.example.com` is
    // how the DNS record is written, `tunnel.example.com` is what a label gets
    // appended to.
    expect(host?.baseDomain).toBe('tunnel.example.com')
    expect(host?.scheme).toBe('https')
    expect(host?.confirmedAt).toBeGreaterThan(0)
    expect(frpSpec().serverAddr).toBe('frp.example.com')
  })
})
